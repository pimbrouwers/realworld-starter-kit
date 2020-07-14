[<AutoOpen>]
module Conduit.Domain

open System.Data
open Donald

[<Struct>]
type NonEmptyString = private NonEmptyString of string with    
    static member value (NonEmptyString str) = str

    static member create (name : string) (str : string) = 
        ConstrainedStrings.createNonEmpty NonEmptyString name str    

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
    static member fromDataReader (rd : IDataReader) =
        {   
            UserId     = rd.GetInt32("user_id")
            Email      = rd.GetString("email")
            Username   = rd.GetString("username")
            Bio        = rd.GetString("bio")
            Image      = rd.GetString("image")
            Password   = rd.GetString("password")
            Salt       = rd.GetString("salt")
            Iterations = rd.GetInt32("iterations")
        }

type NewUser =
    {
        Email      : string        
        Username   : string        
        Password   : string
        Salt       : string
        Iterations : int
    }