module Conduit.Server

open System
open System.Text
open Donald
open Falco    
open Falco.Host
open Microsoft.AspNetCore.Authentication.JwtBearer
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting    
open Microsoft.Extensions.DependencyInjection  
open Microsoft.Extensions.Logging
open Microsoft.IdentityModel.Tokens
open Jwt

type IServiceCollection with
    member this.AddJwtAuthentication (JwtSecret jwtSecret : JwtSecret) =                 
        this.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, fun o ->                                        
                    o.SaveToken <- true 
                    
                    let key = Encoding.ASCII.GetBytes jwtSecret
                    let validationParams = TokenValidationParameters()                    
                    validationParams.IssuerSigningKey <- SymmetricSecurityKey(key)
                    validationParams.ValidateIssuerSigningKey <- true
                    validationParams.ValidateIssuer <- false
                    validationParams.ValidateAudience <- false

                    o.TokenValidationParameters <- validationParams)                
                |> ignore
        this

let handleException 
    (DeveloperMode developerMode : DeveloperMode) : ExceptionHandler =    
    fun (ex : Exception)
        (log : ILogger) ->
        let logMessage = 
            match developerMode with
            | true  -> sprintf "Server error: %s\n\n%s" ex.Message ex.StackTrace
            | false -> "Server Error"
        
        log.Log(LogLevel.Error, logMessage)        
        
        Response.withStatusCode 500
        >> Response.ofPlainText logMessage
    
let handleNotFound : HttpHandler = 
    Response.withStatusCode 404
    >> Response.ofPlainText "Not found"
    
let configureLogging 
    (DeveloperMode developerMode : DeveloperMode)
    (log : ILoggingBuilder) =        
    match developerMode with
    | true  -> LogLevel.Information
    | false -> LogLevel.Error
    |> log.SetMinimumLevel
    |> ignore

let configureServices 
    (jwtSecret : JwtSecret)
    (jwtProvider : JwtProvider)
    (connectionFactory : DbConnectionFactory)
    (services : IServiceCollection) =        
    services.AddCors()
            .AddRouting()        
            .AddJwtAuthentication(jwtSecret)
            .AddAuthorization()
            .AddResponseCaching()
            .AddResponseCompression()            
            .AddSingleton<JwtProvider>(jwtProvider)
            .AddSingleton<DbConnectionFactory>(connectionFactory)
            |> ignore
            
let configure             
    (developerMode : DeveloperMode)        
    (routes : HttpEndpoint list)
    (app : IApplicationBuilder) =             
    app.UseExceptionMiddleware(handleException developerMode)
       .UseResponseCaching()
       .UseResponseCompression()
       .UseStaticFiles()
       .UseRouting()
       .UseCors(fun cors -> cors.AllowAnyOrigin().AllowAnyHeader() |> ignore)
       .UseAuthentication()
       .UseAuthorization()
       .UseHttpEndPoints(routes)
       .UseNotFoundHandler(handleNotFound)
       |> ignore 

let configureWebHost 
    (developerMode : DeveloperMode) 
    (ContentRoot contentRoot : ContentRoot)
    (jwtSecret : JwtSecret) 
    (jwtProvider : JwtProvider)
    (connectionFactory : DbConnectionFactory) : ConfigureWebHost =            
    fun (endpoints : HttpEndpoint list)
        (webHost : IWebHostBuilder) ->
        webHost
            .UseKestrel()
            .UseContentRoot(contentRoot)
            .ConfigureLogging(configureLogging developerMode)
            .ConfigureServices(configureServices jwtSecret jwtProvider connectionFactory)
            .Configure(configure developerMode endpoints)
            |> ignore