[<AutoOpen>]
module Conduit.Common

open System
open TaskResult

type ServiceHandler<'TIn, 'TOut, 'TError> = 'TIn -> TaskResult<'TOut, 'TError>

type ApiError =
    {
        Errors : ApiErrorDetail
    }
and ApiErrorDetail =
    {
        Body : string list
    }

type MaybeBuilder() =
    member _.Bind(x, f) =
        match x with
        | Some x -> f(x)
        | _ -> None
        
    member _.Return(x) = 
        Some x

let maybe = MaybeBuilder()

module StringUtils =
    let inline strEmpty str = String.IsNullOrWhiteSpace(str)

    let inline strNotEmpty str = not(strEmpty str)

type ValidationErrors = ValidationErrors of string list

type ValidationResult<'a> =
    | Success of 'a
    | Failure of ValidationErrors

module ValidationResult = 
    let apply fnResult xResult =
        match fnResult, xResult with
        | Success fn, Success x     -> 
            Success (fn x)

        | Failure errors, Success _ -> 
            Failure errors

        | Success _, Failure errors -> 
            Failure errors
        
        | Failure (ValidationErrors e1), Failure (ValidationErrors e2) -> 
            Failure (ValidationErrors (List.concat [e1;e2]))

    let bind fn xResult =
        match xResult with 
        | Success x      -> fn x
        | Failure errors -> Failure errors

    let map fn xResult =
        match xResult with 
        | Success x      -> fn x |> Success
        | Failure errors -> Failure errors

let (<!>) = ValidationResult.map
let (<*>) = ValidationResult.apply

module ConstrainedStrings =
    let createNonEmpty
        (ctor : string -> 'a)         
        (name : string) 
        (str : string) =
        if StringUtils.strNotEmpty str then Success (ctor str)
        else Failure (ValidationErrors [sprintf "%s must be a non-empty string" name])
