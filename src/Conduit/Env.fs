[<AutoOpen>]
module Conduit.Env

open System    
open System.IO
open Falco.StringUtils
open Microsoft.AspNetCore.Hosting
open Microsoft.Extensions.Configuration

[<Struct>]
type DeveloperMode = DeveloperMode of bool

[<Struct>]
type ContentRoot = ContentRoot of string

[<Struct>]
type JwtSecret = JwtSecret of string

type HttpErrorResponse =
    {
        Errors : HttpErrorResponseBody
    }
and HttpErrorResponseBody =
    {
        Body : string list
    }

let dir = 
    Directory.GetCurrentDirectory()
            
let tryGetEnv (name : string) = 
    match Environment.GetEnvironmentVariable name with 
    | null 
    | ""    -> None 
    | value -> Some value
    
let contentRoot = 
    tryGetEnv WebHostDefaults.ContentRootKey |> Option.defaultValue dir
    |> ContentRoot

let developerMode = 
    match tryGetEnv "ASPNETCORE_ENVIRONMENT" with 
    | None     -> true 
    | Some env -> strEquals env "development" 
    |> DeveloperMode

let config = 
    ConfigurationBuilder()
        .SetBasePath(dir)
        .AddJsonFile("appsettings.json")        
        .Build()