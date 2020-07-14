module Conduit.Article

open System
open Conduit.Profile
open Conduit.Tag

type Comment = 
    {
        Id        : int        
        CreatedAt : DateTime
        UpdatedAt : DateTime
        Body      : string 
        Author    : Profile
    }

type Article = 
    {
        Slug           : string
        Title          : string
        Description    : string
        Body           : string 
        TagList        : Tag list
        CreatedAt      : DateTime
        UpdatedAt      : DateTime
        Favorited      : bool
        FavoritesCount : int
        Author         : Profile
    }