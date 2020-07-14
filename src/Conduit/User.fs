module Conduit.User

open Donald
open Falco
open Falco.StringUtils
open FSharp.Control.Tasks
open Jwt

module User =
    open System.Security.Claims

    let toClaims (user : User) =
        [|
            Claim(ClaimTypes.Sid, user.UserId.ToString())
            Claim(ClaimTypes.NameIdentifier, user.Username)            
        |]

type UserModel =
    {
        Email    : string
        Token    : string
        Username : string
        Bio      : string
        Image    : string
    }
    static member fromUser (token : string) (user : User) =
        {
            Email    = user.Email
            Token    = token
            Username = user.Username
            Bio      = user.Bio
            Image    = user.Image
        }

module Service =
    open System.Security.Claims
    open System.Threading.Tasks
    open Falco.Security
    open TaskResult

    [<CLIMutable>]
    type UserDto<'a> =
        {
            User : 'a
        }
        static member create user = { User = user }
                
    type GenerateJwt =
        Claim[] -> string

    module Details =
        // Dependencies
        type FindUserById =
            int -> Task<User option>

        // Workflow
        type UserDetailsError = InvalidUser
            
        type UserDetailsHandler = ServiceHandler<UserTokenModel, UserModel, UserDetailsError>
        
        // Steps
        type FindUser = FindUserById -> UserTokenModel -> TaskResult<User, UserDetailsError>

        let findUser : FindUser =
            fun findUserById model -> task {
                let! user = findUserById model.UserId

                return
                    match user with
                    | None      -> Error InvalidUser
                    | Some user -> Ok user
            }

        let handle (findUserById : FindUserById) : UserDetailsHandler =
            fun model ->
                model
                |> findUser findUserById
                |> TaskResult.bind (UserModel.fromUser model.Token >> TaskResult.retn)
                

    module LogIn =        
        // Input
        [<CLIMutable>]
        type InputModel =
            {
                Email    : string
                Password : string
            }

        type LoginAttempt =
            {
                Email    : NonEmptyString
                Password : NonEmptyString
            }
            static member create email password =
                fun e p -> { Email = e; Password = p }
                <!> NonEmptyString.create "Email address" email
                <*> NonEmptyString.create "Password" password 

        type LoginAttemptWithUser =
            {
                LoginAttempt : LoginAttempt
                User         : User
            }

        // Dependencies
        type FindUserByEmail =
            string -> Task<User option>

        // Steps
        type UserLoginError =
            | InvalidInput of ValidationErrors
            | EmailNotFound
            | FailedAttempt

        type UserLoginHandler = 
            ServiceHandler<InputModel, UserModel, UserLoginError>

        type ValidateInputModel =
            InputModel -> Result<LoginAttempt, UserLoginError>

        type ResolveUser =
            FindUserByEmail -> LoginAttempt -> TaskResult<LoginAttemptWithUser, UserLoginError>

        type VerifyAttempt =
            GenerateJwt -> LoginAttemptWithUser -> Result<UserModel, UserLoginError>

        // Implementation
        let validateInputModel : ValidateInputModel =
            fun model ->
                match LoginAttempt.create model.Email model.Password with
                | Failure errors ->
                    errors |> InvalidInput |> Error

                | Success loginAttempt ->
                    Ok loginAttempt

        let resolveUser : ResolveUser =
            fun findUserByEmail loginAttempt -> task {
                let! user = findUserByEmail (NonEmptyString.value loginAttempt.Email)
                
                return
                    match user with 
                    | None -> 
                        Error EmailNotFound

                    | Some user ->
                        Ok { 
                            LoginAttempt = loginAttempt
                            User         = user
                        }                    
            }

        let verifyAttempt : VerifyAttempt =
            fun generateJwt loginAttempt ->            
                let attemptHash = 
                    Crypto.sha256
                        loginAttempt.User.Iterations
                        32
                        loginAttempt.User.Salt
                        (NonEmptyString.value loginAttempt.LoginAttempt.Password)

                match attemptHash = loginAttempt.User.Password with
                | false -> 
                    FailedAttempt |> Error

                | true -> 
                    let token =
                        User.toClaims loginAttempt.User
                        |> generateJwt

                    loginAttempt.User 
                    |> UserModel.fromUser token
                    |> Ok
                
        let handle
            (findUserByEmail : FindUserByEmail)
            (generateJwt : GenerateJwt) : UserLoginHandler =
            fun model -> 
                model
                |> validateInputModel |> TaskResult.ofResult
                |> TaskResult.bind (resolveUser findUserByEmail)
                |> TaskResult.bind (verifyAttempt generateJwt >> TaskResult.ofResult)

    module Register =
        // Input
        [<CLIMutable>]
        type InputModel = 
            {
                Username : string
                Email    : string
                Password : string
            }

        type ValidatedInputModel =
            {
                Username : NonEmptyString
                Email    : NonEmptyString
                Password : NonEmptyString
            }
            static member create (model : InputModel) =
                fun u e p -> { 
                    Username = u
                    Email = e
                    Password = p 
                }
                <!> NonEmptyString.create "Username" model.Username
                <*> NonEmptyString.create "Email address" model.Email
                <*> NonEmptyString.create "Password" model.Password

        // Dependencies
        type CreateUser =   
            NewUser -> TaskResult<int, string>

        // Workflow
        type UserRegisterError =
            | InvalidInput of ValidationErrors
            | CreateError of string 

        type UserRegisterHandler =
            ServiceHandler<InputModel, UserModel, UserRegisterError> 

        // Steps
        type ValidateInputModel =
            InputModel -> Result<ValidatedInputModel, UserRegisterError>

        type RegisterUser =
            CreateUser -> ValidatedInputModel -> TaskResult<User, UserRegisterError>

        type VerifyUser =
            GenerateJwt -> User -> UserModel

        // Implementation
        let validateInputModel : ValidateInputModel =
            fun model ->
                match ValidatedInputModel.create model with
                | Failure errors ->
                    errors |> InvalidInput |> Error

                | Success registration ->
                    Ok registration

        let registerUser : RegisterUser =
            fun createUser registration -> task {
                let salt = Crypto.createSalt 16
                let iterations = Crypto.randomInt 150000 200000
                let passwordHash = Crypto.sha256 iterations 32 salt (NonEmptyString.value registration.Password)
                let user = 
                    {
                        Email      = NonEmptyString.value registration.Email
                        Username   = NonEmptyString.value registration.Username
                        Password   = passwordHash
                        Salt       = salt
                        Iterations = iterations
                    }

                let! userId = createUser user
                
                return 
                    match userId with
                    | Error error -> 
                        Error (CreateError error)

                    | Ok userId ->
                        Ok {
                            UserId     = userId
                            Email      = user.Email
                            Username   = user.Username
                            Bio        = null
                            Image      = null
                            Password   = user.Password
                            Salt       = user.Salt
                            Iterations = user.Iterations
                        }
            }

        let verifyUser : VerifyUser =
            fun generateJwt user ->                
                let token =
                    User.toClaims user
                    |> generateJwt
                
                user
                |> UserModel.fromUser token

        let handle 
            (createUser : CreateUser)
            (generateJwt : GenerateJwt)
            : UserRegisterHandler =
            fun model ->
                model
                |> validateInputModel |> TaskResult.ofResult
                |> TaskResult.bind (registerUser createUser)
                |> TaskResult.bind (verifyUser generateJwt >> TaskResult.retn)
     
    module Update =
        // Input
        [<CLIMutable>]
        type InputModel =
            {
               Email    : string               
               Username : string
               Password : string
               Bio      : string
               Image    : string 
            }

        type ValidatedInputModel =
            {                
                Email    : NonEmptyStringOrNull
                Username : NonEmptyStringOrNull
                Password : NonEmptyStringOrNull
                Bio      : NonEmptyStringOrNull
                Image    : NonEmptyStringOrNull
            }
            static member create (model : InputModel) =
                fun u e p b i -> {                     
                    Username = u
                    Email    = e
                    Password = p
                    Bio      = b
                    Image    = i
                }
                <!> NonEmptyStringOrNull.create "Username" model.Username
                <*> NonEmptyStringOrNull.create "Email address" model.Email
                <*> NonEmptyStringOrNull.create "Password" model.Password
                <*> NonEmptyStringOrNull.create "Bio" model.Bio
                <*> NonEmptyStringOrNull.create "Image" model.Image
      
        type ResolvedInputModel =
            {
                Input : ValidatedInputModel
                User  : User
            }

        // Dependencies
        type FindUserById =
            int -> Task<User option>

        type UpdateUser =
            User -> TaskResult<unit, string>

        // Workflow
        type UserUpdateError =
            | InvalidInput of ValidationErrors
            | InvalidUser
            | UpdateError of string

        type UserUpdateHandler =
            ServiceHandler<InputModel, UserModel, UserUpdateError>

        // Steps
        type ValidateInputModel =
            InputModel -> Result<ValidatedInputModel, UserUpdateError>

        type ResolveUser =
            FindUserById -> int -> ValidatedInputModel -> TaskResult<ResolvedInputModel, UserUpdateError>

        type UpdateUserDetails =
            UpdateUser -> string -> ResolvedInputModel -> TaskResult<UserModel, UserUpdateError>

        // Implementation
        let validateInputModel : ValidateInputModel = 
            fun model ->
                match ValidatedInputModel.create model with
                | Failure errors ->
                    errors |> InvalidInput |> Error

                | Success validateInputModel ->
                    Ok validateInputModel
        
        let resolveUser : ResolveUser =
            fun findUserById userId model -> task {
                let! user = findUserById userId

                return
                    match user with
                    | None      -> Error InvalidUser
                    | Some user -> Ok { Input = model; User = user }
            }
                
        let updateUserDetails : UpdateUserDetails =
            fun updateUser token model -> task {
                let password = 
                    let password = NonEmptyStringOrNull.value model.Input.Password
                    if StringUtils.strNotEmpty password then Crypto.sha256 model.User.Iterations 32 model.User.Salt password
                    else model.User.Password

                let user = 
                    let email = NonEmptyStringOrNull.value model.Input.Email
                    let username = NonEmptyStringOrNull.value model.Input.Username
                    let bio = NonEmptyStringOrNull.value model.Input.Bio
                    let image = NonEmptyStringOrNull.value model.Input.Image

                    { model.User with 
                        Email    = if strNotEmpty email then email else model.User.Email
                        Username = if strNotEmpty username then username else model.User.Username
                        Bio      = if strNotEmpty bio then bio else model.User.Bio
                        Image    = if strNotEmpty image then image else model.User.Image
                        Password = password }
                
                let! updateResult = user |> updateUser

                return 
                    match updateResult with
                    | Error error -> Error (UpdateError error)
                    | Ok () -> Ok (UserModel.fromUser token user)
            }

        let handle 
            (findUserById : FindUserById)
            (updateUser : UpdateUser)
            (userToken : UserTokenModel) : UserUpdateHandler =
            fun model ->
                model
                |> validateInputModel |> TaskResult.ofResult
                |> TaskResult.bind (resolveUser findUserById userToken.UserId)
                |> TaskResult.bind (updateUserDetails updateUser userToken.Token)
                
module Db =
    open System
    open System.Data
    
    let fromDataReader (rd : IDataReader) =
        {   
            UserId     = rd.GetInt32("api_user_id")
            Email      = rd.GetString("email")
            Username   = rd.GetString("username")
            Bio        = rd.GetString("bio")
            Image      = rd.GetString("image")
            Password   = rd.GetString("password")
            Salt       = rd.GetString("salt")
            Iterations = rd.GetInt32("iterations")
        }

    module User =  
        let create (conn : IDbConnection) (user : NewUser) = task {
            let! result =
                tryScalarAsync
                    "INSERT  api_user (email, username, password, salt, iterations)
                     SELECT  *
                     FROM    (SELECT @email AS email, @username AS username, @password AS password, @salt AS salt, @iterations AS iterations) AS n
                     WHERE   NOT EXISTS (SELECT 1 FROM api_user WHERE email = @email);

                     SELECT  api_user_id
                     FROM    api_user
                     WHERE   email = @email;"
                    [
                        newParam "email"      (SqlType.String user.Email)
                        newParam "username"   (SqlType.String user.Username)
                        newParam "password"   (SqlType.String user.Password)
                        newParam "salt"       (SqlType.String user.Salt)
                        newParam "iterations" (SqlType.Int user.Iterations)
                    ]
                    Convert.ToInt32
                    conn
            return 
                 match result with
                 | DbError error -> Error error.Message
                 | DbResult user -> Ok user
        }

        let tryGet (conn : IDbConnection) (userId : int) =
            querySingleAsync
                "SELECT  api_user_id
                       , email
                       , username
                       , bio
                       , image
                       , password
                       , salt
                       , iterations
                 FROM    api_user
                 WHERE   api_user_id = @api_user_id"
                [ 
                    newParam "api_user_id" (SqlType.Int (userId)) 
                ]
                fromDataReader
                conn

        let tryFind (conn : IDbConnection) (email : string) =
            querySingleAsync 
                "SELECT  api_user_id
                       , email
                       , username
                       , bio
                       , image
                       , password
                       , salt
                       , iterations
                 FROM    api_user
                 WHERE   email = @email"
                [ 
                    newParam "email" (SqlType.String (email)) 
                ]
                fromDataReader
                conn
        
        let update (conn : IDbConnection) (user : User) = task {
            let! result =
                tryExecAsync
                    "UPDATE  api_user 
                     SET     email = @email
                           , username = @username
                           , password = @password
                           , bio = @bio
                           , image = @image
                     WHERE   api_user_id = @user_id"
                    [
                        newParam "user_id"  (SqlType.Int user.UserId)
                        newParam "email"    (SqlType.String user.Email)
                        newParam "username" (SqlType.String user.Username)
                        newParam "password" (SqlType.String user.Password)
                        newParam "bio"      (SqlType.String user.Bio)
                        newParam "image"    (SqlType.String user.Image)
                    ]                    
                    conn
            return 
                 match result with
                 | DbError error -> Error error.Message
                 | DbResult user -> Ok user
        }
  
open Service

let handleDetails : HttpHandler =
    let handleDetailsInput userTokenModel : HttpHandler =
        fun ctx -> task {        
            let connectionFactory = ctx.GetService<DbConnectionFactory>()
            use conn = createConn connectionFactory

            let serviceHandler = 
                Details.handle (Db.User.tryGet conn)
                
            let errorProcessor error =
                match error with
                | Details.InvalidUser -> ["Could not find user"]

            return!
                handleService
                    serviceHandler
                    UserDto<UserModel>.create
                    errorProcessor
                    userTokenModel
                    ctx
        }

    handleBindToken handleDetailsInput

let handleLogin : HttpHandler =    
    let handleLoginInput inputModel : HttpHandler = 
        fun ctx -> task {
            let jwtProvider = ctx.GetService<JwtProvider>()
            let connectionFactory = ctx.GetService<DbConnectionFactory>()
            use conn = createConn connectionFactory

            let serviceHandler = 
                LogIn.handle (Db.User.tryFind conn) jwtProvider

            let errorProcessor error = 
                match error with
                | LogIn.InvalidInput (ValidationErrors errors) -> 
                    errors

                | _ -> 
                    ["Invalid email/password"]
                
            return! 
                handleService 
                    serviceHandler                     
                    UserDto<UserModel>.create
                    errorProcessor 
                    inputModel.User
                    ctx
        }

    handleBindJson<UserDto<LogIn.InputModel>> handleLoginInput

let handleRegister : HttpHandler = 
    let handleRegisterInput inputModel : HttpHandler =
        fun ctx -> task {
            let jwtProvider = ctx.GetService<JwtProvider>()
            let connectionFactory = ctx.GetService<DbConnectionFactory>()
            use conn = createConn connectionFactory

            let serviceHandler = Register.handle (Db.User.create conn) jwtProvider
            let errorProcessor error = 
                match error with
                | Register.InvalidInput (ValidationErrors errors) -> 
                    errors

                | Register.CreateError error -> 
                    [error]
                
            return! 
                handleService 
                    serviceHandler 
                    UserDto<UserModel>.create
                    errorProcessor 
                    inputModel.User
                    ctx            
        }

    handleBindJson<UserDto<Register.InputModel>> handleRegisterInput

let handleUpdate : HttpHandler =    
    let handleUpdateInput userToken inputModel : HttpHandler =
        fun ctx -> task {
            let connectionFactory = ctx.GetService<DbConnectionFactory>()
            use conn = createConn connectionFactory

            let serviceHandler = 
                Update.handle (Db.User.tryGet conn) (Db.User.update conn) userToken
                
            let errorProcessor error =
                match error with
                | Update.InvalidInput (ValidationErrors errors) -> errors
                | Update.InvalidUser -> ["Could not find user"]
                | Update.UpdateError error -> [error]

            return!
                handleService
                    serviceHandler
                    UserDto<UserModel>.create
                    errorProcessor
                    inputModel.User
                    ctx
        }

    let handleTokenBound userToken : HttpHandler =
        handleBindJson<UserDto<Update.InputModel>> (handleUpdateInput userToken)

    handleBindToken handleTokenBound