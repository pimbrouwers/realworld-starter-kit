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

module Db =
    open System.Data

    module Profile =
        let fromDataReader (rd : IDataReader) =
            {
                Username  = rd.GetString("username")
                Bio       = rd.GetString("bio")
                Image     = rd.GetString("image")
                Following = rd.GetBoolean("following")
            }

        let tryFind 
            (conn : IDbConnection) 
            (currentUserId : int option)
            (username : string) =
            let userIdParamAndQuery =
                match currentUserId with
                | None -> 
                    let query =
                        "SELECT  username, bio, image, CAST (0 AS BIT) AS following
                         FROM    api_user                                
                         WHERE   api_user.username = @username"

                    SqlType.Null, query

                | Some userId -> 
                    let query =
                        "SELECT  username
                               , bio
                               , image
                               , CAST (CASE WHEN follow.api_user_id IS NULL THEN 0 ELSE 1 END AS BIT) AS following
                         FROM    api_user
                                 LEFT JOIN follow 
                                    ON follow.follow_api_user_id = api_user.api_user_id
                                    AND follow.api_user_id = @api_user_id
                         WHERE   api_user.username = @username"

                    SqlType.Int userId, query

            querySingleAsync
                (snd userIdParamAndQuery)
                [
                    newParam "api_user_id" (fst userIdParamAndQuery)
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