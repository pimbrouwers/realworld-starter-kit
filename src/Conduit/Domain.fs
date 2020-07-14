[<AutoOpen>]
module Conduit.Domain

open System.Data
open Donald

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

type User = 
    {
        UserId     : int
        Email      : string        
        Username   : string
        Bio        : string
        Image      : string
        Password   : string
        Salt       : string
        Iterations : int 
    }
    
type NewUser =
    {
        Email      : string        
        Username   : string        
        Password   : string
        Salt       : string
        Iterations : int
    }