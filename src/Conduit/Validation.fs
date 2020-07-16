module Conduit.Validation

type ValidationErrors = ValidationErrors of string list

type ValidationResult<'a> =
    | Success of 'a
    | Failure of ValidationErrors

module ValidationResult = 
    let apply fnResult xResult =
        match fnResult, xResult with
        | Success fn, Success x                                        -> Success (fn x)
        | Failure errors, Success _                                    -> Failure errors
        | Success _, Failure errors                                    -> Failure errors            
        | Failure (ValidationErrors e1), Failure (ValidationErrors e2) -> Failure (ValidationErrors (List.concat [e1;e2]))

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
        if String.notEmpty str then Success (ctor str)
        else Failure (ValidationErrors [sprintf "%s must be a non-empty string" name])

    let createNonEmptyOrNull
        (ctor : string -> 'a)         
        (name : string) 
        (str : string) =
        if str = null || String.notEmpty str then Success (ctor str)
        else Failure (ValidationErrors [sprintf "%s must be a non-empty string or null" name])

[<Struct>]
type NonEmptyString = private NonEmptyString of string with    
    static member value (NonEmptyString str) = str

    static member create (name : string) (str : string) = 
        ConstrainedStrings.createNonEmpty NonEmptyString name str    

[<Struct>]
type NonEmptyStringOrNull = private NonEmptyStringOrNull of string with    
    static member value (NonEmptyStringOrNull str) = str
    
    static member create (name : string) (str : string) = 
        ConstrainedStrings.createNonEmptyOrNull NonEmptyStringOrNull name str    

