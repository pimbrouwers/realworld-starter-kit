module Conduit.Server

open System
open Falco    
open Falco.Host
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Hosting    
open Microsoft.Extensions.DependencyInjection  
open Microsoft.Extensions.Logging

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
    
let configureWebHost 
    (developerMode : DeveloperMode) : ConfigureWebHost =            
    let configureLogging 
        (DeveloperMode developerMode : DeveloperMode)
        (log : ILoggingBuilder) =        
        match developerMode with
        | true  -> LogLevel.Debug
        | false -> LogLevel.Error
        |> log.SetMinimumLevel
        |> ignore

    let configureServices 
        (services : IServiceCollection) =
        services.AddRouting()     
                .AddResponseCaching()
                .AddResponseCompression()
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
            .UseHttpEndPoints(routes)
            .UseNotFoundHandler(handleNotFound)
            |> ignore 

    fun (endpoints : HttpEndpoint list)
        (webHost : IWebHostBuilder) ->                              
        webHost
            .UseKestrel()
            .ConfigureLogging(configureLogging developerMode)
            .ConfigureServices(configureServices)
            .Configure(configure developerMode endpoints)
            |> ignore