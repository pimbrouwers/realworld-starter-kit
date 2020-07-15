namespace Conduit

[<AutoOpen>]
module Common =    
    let jwtHeaderPrefix = "Token "

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


module StringUtils =
    open System 

    let inline strEmpty str = String.IsNullOrWhiteSpace(str)

    let inline strNotEmpty str = not(strEmpty str)

module ConstrainedStrings =
    let createNonEmpty
        (ctor : string -> 'a)         
        (name : string) 
        (str : string) =
        if StringUtils.strNotEmpty str then Success (ctor str)
        else Failure (ValidationErrors [sprintf "%s must be a non-empty string" name])

    let createNonEmptyOrNull
        (ctor : string -> 'a)         
        (name : string) 
        (str : string) =
        if str = null || StringUtils.strNotEmpty str then Success (ctor str)
        else Failure (ValidationErrors [sprintf "%s must be a non-empty string or null" name])