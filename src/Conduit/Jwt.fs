module Jwt

open System
open System.IdentityModel.Tokens.Jwt
open System.Security.Claims
open System.Text
open Microsoft.IdentityModel.Tokens

type JwtProvider =
    Claim[] -> string

let generateToken     
    (key : string)    
    (expirationMinutes : float)
    (claims : Claim array) = 
    let tokenHandler = JwtSecurityTokenHandler()
    
    let keyBytes = Encoding.ASCII.GetBytes(key)    
    let identity = ClaimsIdentity(claims)
    let expiryDate = DateTime.UtcNow.AddMinutes(expirationMinutes)
    let signingCreds = SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256Signature)
    
    SecurityTokenDescriptor(Subject = identity, Expires = Nullable(expiryDate), SigningCredentials = signingCreds)
    |> tokenHandler.CreateToken
    |> tokenHandler.WriteToken