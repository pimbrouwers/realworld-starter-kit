module Conduit.Middleware

open Falco
open Falco.Security

let ifAuthenticated (handler : HttpHandler) : HttpHandler =
    fun ctx ->
        let respondWith =
            match Auth.isAuthenticated ctx with
            | false -> handleUnauthorized
            | true -> handler

        respondWith ctx

