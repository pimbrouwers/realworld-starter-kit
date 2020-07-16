[<AutoOpen>]
module Conduit.Domain

open System

type ApiUser = 
    {
        ApiUserId  : int
        Email      : string        
        Username   : string
        Bio        : string
        Image      : string
        Password   : string
        Salt       : string
        Iterations : int 
    }
    
type NewApiUser =
    {
        Email      : string        
        Username   : string        
        Password   : string
        Salt       : string
        Iterations : int
    }

type Follow =
    {
        ApiUserId       : int
        FollowApiUserId : int
    }