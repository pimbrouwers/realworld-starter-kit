module Conduit.User

open Donald
open Falco
open FSharp.Control.Tasks
open Jwt

type UserModel =
    {
        Email    : string
        Token    : string
        Username : string
        Bio      : string
        Image    : string
    }
    static member fromUser (user : User) (token : string) =
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
    type UserEnvelope<'a> =
        {
            User : 'a
        }

    type GenerateJwt =
        Claim[] -> string

    let getUserClaims (user : User) =
        [|
            Claim(ClaimTypes.Sid, user.UserId.ToString())
            Claim(ClaimTypes.Email, user.Email)
        |]

    module Login =        
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
            ServiceHandler<UserEnvelope<InputModel>, UserModel, UserLoginError>

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
                    getUserClaims loginAttempt.User
                    |> generateJwt
                    |> UserModel.fromUser loginAttempt.User 
                    |> Ok
                
        let handle
            (findUserByEmail : FindUserByEmail)
            (generateJwt : GenerateJwt) : UserLoginHandler =
            fun model -> 
                model.User
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

        type Registration =
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
            ServiceHandler<UserEnvelope<InputModel>, UserModel, UserRegisterError> 

        // Steps
        type ValidateInputModel =
            InputModel -> Result<Registration, UserRegisterError>

        type RegisterUser =
            CreateUser -> Registration -> TaskResult<User, UserRegisterError>

        type VerifyUser =
            GenerateJwt -> User -> UserModel

        // Implementation
        let validateInputModel : ValidateInputModel =
            fun model ->
                match Registration.create model with
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
                getUserClaims user
                |> generateJwt
                |> UserModel.fromUser user

        let handle 
            (createUser : CreateUser)
            (generateJwt : GenerateJwt)
            : UserRegisterHandler =
            fun model ->
                model.User
                |> validateInputModel |> TaskResult.ofResult
                |> TaskResult.bind (registerUser createUser)
                |> TaskResult.bind (verifyUser generateJwt >> TaskResult.retn)
            
module Db =
    open System.Data

    module User =        
        let tryFindAsync (conn : IDbConnection) (email : string) =
            querySingleAsync 
                "SELECT  user_id
                       , email
                       , username
                       , bio
                       , image
                       , password
                       , salt
                       , iterations
                 FROM    user
                 WHERE   email = @email"
                [ 
                    newParam "email" (SqlType.String (email)) 
                ]
                User.fromDataReader
                conn
  
open Service

let handleLogin : HttpHandler =
    fun ctx -> task {                        
        let handleWorkflowError error : HttpHandler =            
            let errors = 
                match error with
                | Login.InvalidInput (ValidationErrors errors) -> 
                    errors

                | _ -> 
                    ["Invalid email/password"]

            {
                Errors = { Body = errors }
            }
            |> Response.ofJsonCamelCase 

        let handleWorkflowSuccess user : HttpHandler =
            Response.ofJsonCamelCase user

        let handleWorkFlow inputModel : HttpHandler = 
            fun ctx -> task {
                let jwtProvider = ctx.GetService<JwtProvider>()
                let connectionFactory = ctx.GetService<DbConnectionFactory>()
                use conn = createConn connectionFactory

                let! result =
                    Login.handle
                        (Db.User.tryFindAsync conn)
                        jwtProvider
                        inputModel

                do! 
                    match result with 
                    | Error error -> handleWorkflowError error ctx
                    | Ok user     -> handleWorkflowSuccess user ctx
            }

        let! inputModel = Request.tryBindJson<UserEnvelope<Login.InputModel>> ctx
        
        let respondWith =
            match inputModel with
            | Error error  -> 
                { 
                    Errors = { Body = [error] } 
                }
                |> Response.ofJsonCamelCase

            | Ok inputModel -> 
                handleWorkFlow inputModel

        return! respondWith ctx
    }