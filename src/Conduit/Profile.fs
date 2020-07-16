module Conduit.Profile

open Donald
open Falco
open FSharp.Control.Tasks

type ProfileModel = 
    {
        Username  : string
        Bio       : string
        Image     : string
        Following : bool
    }

[<CLIMutable>]
type ProfileDto =
    {
        Profile : ProfileModel
    }
    static member create profile = { Profile = profile }

module Service = 
    open System.Threading.Tasks

    module ProfileDetails =   
        // Input 
        type InputModel =
            {
                Username    : string
                CurrentUser : UserTokenModel option
            }

        // Dependencies 
        type FindProfileByUsername =
            int option -> string -> Task<ProfileModel option>

        // Workflow
        type ProfileDetailsError = 
            InvalidUser

        type ProfileDetailsHandler = 
            ServiceHandler<InputModel, ProfileModel, ProfileDetailsError>

        // Steps 
        type FindUser =
            FindProfileByUsername -> InputModel -> TaskResult<ProfileModel, ProfileDetailsError>

        // Implementaiton
        let findUser : FindUser =
            fun findProfileByUsername model -> task {
                let currentUserId = match model.CurrentUser with None -> None | Some u -> Some u.UserId
                let! profile = findProfileByUsername currentUserId model.Username
                
                return 
                    match profile with
                    | None -> Error InvalidUser
                    | Some profile -> Ok profile                    
            }

        let handle 
            (findProfileByUsername : FindProfileByUsername) : ProfileDetailsHandler =
            fun model ->
                model 
                |> findUser findProfileByUsername


    module ProfileFollow =
        // Input
        type InputModel =
            {
                Username     : string
                CurrentUser  : UserTokenModel
            }

        // Dependencies
        type CreateFollow =
            NewFollow -> TaskResult<unit, string>

        type FindProfileByUsername =
            int -> string -> Task<ProfileModel option>

        // Workflow 
        type ProfileFollowError = 
            | CreateError of string
            | InvalidUser 

        type ProfileFollowHandler = 
            ServiceHandler<InputModel, ProfileModel, ProfileFollowError>

        // Steps
        type FollowProfile =
            CreateFollow -> InputModel -> TaskResult<InputModel, ProfileFollowError>

        type FindProfile =
            FindProfileByUsername -> InputModel -> TaskResult<ProfileModel, ProfileFollowError>

        // Implementation
        let followProfile : FollowProfile =
            fun createFollow model -> task {
                let! result = 
                    createFollow 
                        { ApiUserId = model.CurrentUser.UserId; FollowUsername = model.Username }
                
                return
                    match result with
                    | Error error -> Error (CreateError error)
                    | Ok () -> Ok model
            }

        let findProfile : FindProfile =
            fun findProfileByUsername model -> task {
                let! profile = findProfileByUsername model.CurrentUser.UserId model.Username
                return 
                    match profile with
                    | None         -> Error InvalidUser
                    | Some profile -> Ok profile
            }

        let handle 
            (createFollow : CreateFollow)
            (findProfileByUserId : FindProfileByUsername)
            : ProfileFollowHandler =
            fun model ->
                model
                |> followProfile createFollow 
                |> TaskResult.bind (findProfile findProfileByUserId)

module Db =
    open System.Data

    module Follow =
        let create (conn : IDbConnection) (follow : NewFollow) = task {
            let! result = 
                tryExecAsync
                    "INSERT  follow (api_user_id, follow_api_user_id)
                     SELECT  @api_user_id, api_user_id
                     FROM    api_user
                     WHERE   username = @follow_username
                             AND api_user_id <> @api_user_id
                             AND api_user_id NOT IN (
                                SELECT  follow_api_user_id 
                                FROM    follow 
                                WHERE   api_user_id = @api_user_id);"
                    [
                        newParam "api_user_id" (SqlType.Int follow.ApiUserId)
                        newParam "follow_username" (SqlType.String follow.FollowUsername)
                    ]
                    conn

            return DbResult.toResult result
        }

        let delete (conn : IDbConnection) (follow : Follow) = task {
            let! result = 
                tryExecAsync
                    "DELETE  
                     FROM    follow
                     WHERE   api_user_id = @api_user_id
                             AND follow_api_user_id = @follow_api_user_id);"
                    [
                        newParam "api_user_id" (SqlType.Int follow.ApiUserId)
                        newParam "follow_api_user_id" (SqlType.Int follow.FollowApiUserId)
                    ]
                    conn

            return DbResult.toResult result
        }
            

    module Profile =
        let fromDataReader (rd : IDataReader) =
            {
                Username  = rd.GetString("username")
                Bio       = rd.GetString("bio")
                Image     = rd.GetString("image")
                Following = rd.GetBoolean("following")
            }

        let tryGet (conn : IDbConnection) (currentUserId : int) (followUserId : int) =
            querySingleAsync
                "SELECT  username
                       , bio
                       , image
                       , CAST (CASE WHEN follow.api_user_id IS NULL THEN 0 ELSE 1 END AS BIT) AS following
                 FROM    api_user
                         LEFT JOIN follow 
                           ON follow.follow_api_user_id = api_user.api_user_id
                           AND follow.api_user_id = @api_user_id
                 WHERE   api_user.api_user_id = @follow_api_user_id"
                 [
                    newParam "api_user_id" (SqlType.Int currentUserId)
                    newParam "follow_api_user_id" (SqlType.Int followUserId)
                 ]
                 fromDataReader
                 conn

        let tryFind 
            (conn : IDbConnection) 
            (currentUserId : int option)
            (username : string) =
            let userIdParamAndQuery =
                match currentUserId with
                | None        -> SqlType.Null                    
                | Some userId -> SqlType.Int userId

            querySingleAsync
                "SELECT  username
                       , bio
                       , image
                       , CAST (CASE WHEN follow.api_user_id IS NULL THEN 0 ELSE 1 END AS BIT) AS following
                 FROM    api_user
                         LEFT JOIN follow 
                            ON follow.follow_api_user_id = api_user.api_user_id
                            AND follow.api_user_id = @api_user_id
                 WHERE   api_user.username = @username"  
                [
                    newParam "api_user_id" userIdParamAndQuery
                    newParam "username" (SqlType.String username)
                ]
                fromDataReader
                conn

open Service

let handleDetails : HttpHandler =
    let handleDetailsInput userTokenModel : HttpHandler =
        fun ctx -> task {
            let connectionFactory = ctx.GetService<DbConnectionFactory>()
            use conn = createConn connectionFactory

            let username = 
                ctx 
                |> Request.tryGetRouteValue "username" 
                |> Option.defaultValue ""

            let serviceHandler = 
                ProfileDetails.handle (Db.Profile.tryFind conn)
                
            let errorProcessor error =
                match error with
                | ProfileDetails.InvalidUser -> ["Could not find user"]

            return!
                handleService
                    serviceHandler
                    ProfileDto.create
                    errorProcessor
                    { Username = username; CurrentUser = userTokenModel }
                    ctx
        }

    handleBindTokenOption handleDetailsInput

let handleFollow : HttpHandler =
    let handleFollowInput userTokenModel : HttpHandler =
        fun ctx -> task {
            let connectionFactory = ctx.GetService<DbConnectionFactory>()
            use conn = createConn connectionFactory

            let username = 
                ctx 
                |> Request.tryGetRouteValue "username" 
                |> Option.defaultValue ""

            let serviceHandler =
                ProfileFollow.handle 
                    (Db.Follow.create conn) 
                    (fun userId username -> Db.Profile.tryFind conn (Some userId) username)

            let errorProcessor error =
                match error with
                | ProfileFollow.CreateError error -> [error]
                | ProfileFollow.InvalidUser -> ["Could not find user"]

            return!
                handleService
                    serviceHandler
                    ProfileDto.create
                    errorProcessor
                    { Username = username; CurrentUser = userTokenModel }
                    ctx
        }

    handleBindToken handleFollowInput