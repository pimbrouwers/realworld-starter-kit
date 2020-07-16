[<AutoOpen>]
module Conduit.Api

open System.Security.Claims
open Falco
open FSharp.Control.Tasks
open TaskResult
open Jwt

type ServiceHandler<'TIn, 'TOut, 'TError> = 'TIn -> TaskResult<'TOut, 'TError>
type ServiceResultProcessor<'TOut, 'TOutNew> = 'TOut -> 'TOutNew
type ServiceErrorProcessor<'TError> = 'TError -> string list

type UserTokenModel =
    {
        UserId : int
        Token  : string
    }

module Request =    
    open Microsoft.AspNetCore.Http

    let getHeader 
        (headerName : string)
        (ctx : HttpContext) : string[] =
        ctx.Request.Headers.[headerName].ToArray()

module Response =
    open System.Text.Json
    
    let ofJsonCamelCase (jsonObj : 'a) : HttpHandler =
        let jsonOptions = JsonSerializerOptions()
        jsonOptions.PropertyNamingPolicy <- JsonNamingPolicy.CamelCase        
        Response.ofJsonOptions jsonObj jsonOptions

module Principal =
    open Microsoft.AspNetCore.Http

    let getSid
        (ctx : HttpContext) : int option =
        let i = ctx.User.Identity :?> ClaimsIdentity
        match i.FindFirst(ClaimTypes.Sid).Value with
        | null -> ""
        | v -> v
        |> StringParser.parseInt
         

let handleServiceError errors : HttpHandler =    
    {|
        Errors = {| Body = errors |}
    |}
    |> Response.ofJsonCamelCase 

let handleUnauthorized =
    Response.withStatusCode 401
    >> handleServiceError [ "Not authorized" ]

let handleNotFound : HttpHandler = 
    Response.withStatusCode 404
    >> Response.ofPlainText "Not found"

let handleBindJson<'a> (handler : 'a -> HttpHandler) =
    fun ctx -> task {
        let! inputModel = Request.tryBindJson<'a> ctx
        
        let respondWith =
            match inputModel with
            | Error error  -> 
                handleServiceError [error]

            | Ok inputModel -> 
                handler inputModel

        return! respondWith ctx
    }

let handleBindTokenOption
    (handler : UserTokenModel option -> HttpHandler) : HttpHandler =
    fun ctx ->
        let userId = Principal.getSid ctx        
        let token = Request.getHeader "Authorization" ctx
        
        let model =
            match userId , token with
            | Some userId, [|token|] ->                            
                Some { 
                    UserId = userId
                    Token = token.Substring(jwtHeaderPrefix.Length)
                }
            
            | _ -> None
                

        (model |> handler) ctx

let handleBindToken 
    (handler : UserTokenModel -> HttpHandler) : HttpHandler =    
    let tokenHandler userToken : HttpHandler =
        fun ctx ->                        
            let respondWith =
                match userToken with
                | Some userToken -> userToken |> handler            
                | _              -> handleUnauthorized

            respondWith ctx

    handleBindTokenOption tokenHandler

let handleService
    (serviceHandler : ServiceHandler<'TIn, 'TResult, 'TError>)
    (resultProcessor : ServiceResultProcessor<'TResult, 'TOutNew>)
    (errorProcessor : ServiceErrorProcessor<'TError>)
    (inputModel : 'TIn) : HttpHandler = 
    fun ctx -> task {        
        let! serviceResult = serviceHandler inputModel

        let respondWith = 
            match serviceResult with 
            | Error error ->                 
                errorProcessor error
                |> handleServiceError

            | Ok result   -> 
                Response.ofJsonCamelCase (resultProcessor result)

        return! respondWith ctx
    }
