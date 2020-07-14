module Conduit.Program

open System.Data
open Donald
open Falco
open Microsoft.Extensions.Configuration
open Microsoft.Data.Sqlite
open Jwt

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
                let conn = new SqliteConnection(connectionString) 
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
                post "/api/users/login" User.handleLogin
            ]
        0
    with
    | _ -> -1