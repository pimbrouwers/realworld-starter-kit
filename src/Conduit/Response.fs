[<AutoOpen>]
module Conduit.Response

open System.Text.Json
open Falco 

let ofJsonCamelCase (jsonObj : 'a) : HttpHandler =
    let jsonOptions = JsonSerializerOptions()
    jsonOptions.PropertyNamingPolicy <- JsonNamingPolicy.CamelCase        
    Response.ofJsonOptions jsonObj jsonOptions



