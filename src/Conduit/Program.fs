module Conduit.Program

open System.Data
open System.Data.SqlClient
open Donald
open Falco
open Microsoft.Extensions.Configuration
open Jwt
open Middleware

[<EntryPoint>]
let main args =    
    try                   
        let jwtSecret = 
            Env.config.GetValue("jwt:secret")            

        let jwtProvider : JwtProvider =            
            let expirationMinutes =
                float (60 * 24 * 7)

            fun claims -> 
                Jwt.generateToken jwtSecret expirationMinutes claims
               
        let connectionString = 
            Env.config.GetConnectionString("Default")

        let connectionFactory : DbConnectionFactory =         
            fun () -> 
                let conn = new SqlConnection(connectionString) 
                conn.Open()
                conn :> IDbConnection        
        
        Host.startWebHost 
            args
            (Server.configureWebHost 
                Env.developerMode 
                Env.contentRoot 
                (JwtSecret jwtSecret)
                jwtProvider
                connectionFactory)
            [           
                get  "/api/user"        (ifAuthenticated User.handleDetails)
                put  "/api/user"        (ifAuthenticated User.handleUpdate)
                post "/api/users"       User.handleRegister
                post "/api/users/login" User.handleLogin

                get  "/api/profiles/{username:required}"        Profile.handleDetails
                post "/api/profiles/{username:required}/follow" (ifAuthenticated Profile.handleFollow)
            ]
        0
    with
    | _ -> -1