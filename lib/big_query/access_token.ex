defmodule BigQuery.AccessToken do
  use Fun.Core

  import Fun.Either
  alias Fun.Either.Either.{Left, Right}

  alias Ebach.{S3Utils}
  
  @moduledoc """
  Retrieve a Google Cloud Access Token scoped to BigQuery
  """
  # Based on https://gist.github.com/plamb/8c8f39cfba9e69cb034a/871a9b8128117518cdfbbf46b4cd405b5353f6c6
  @spec get_token :: {:ok, String.t} | {:error, String.t}
  def get_token() do

    result = mdo do
      key_file = Application.get_env(:big_query, :bigquery_private_key_path) |> IO.inspect

      key_json <- File.read(key_file)
      key_map <- Poison.decode(key_json)

      jwk = JOSE.JWK.from_pem(key_map["private_key"])

      jws = %{"alg" => "RS256"}
      
      header = %{
        "alg" => "RS256",
        "typ" => "JWT"
      }
      
      iat = :os.system_time(:seconds)
      exp = iat + 3600

      bigquery_scope = Application.get_env(:big_query, :bigquery_scope, "")
    
      claims = %{
        "iss" => key_map["client_email"],
        "scope" => "#{bigquery_scope} https://www.googleapis.com/auth/bigquery.readonly https://www.googleapis.com/auth/bigquery.insertdata https://www.googleapis.com/auth/bigquery",
        "aud" => "https://www.googleapis.com/oauth2/v3/token",
        "exp" => exp,
        "iat" => iat
      }

      encoded_claims <- Poison.encode(claims)
          
      {_alg, compacted} = JOSE.JWS.sign(jwk, encoded_claims, header, jws)
      |> JOSE.JWS.compact

      token_auth_uri = "https://www.googleapis.com/oauth2/v3/token"
      headers = %{"Content-type" => "application/x-www-form-urlencoded"}
      form = {:form, [assertion: compacted, grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer"]}

      token_response <- HTTPoison.post(token_auth_uri, form, headers)
      token_json <- Poison.decode(token_response.body)

      return.(token_json)
    end

    case result do
      %Right{value: value} -> {:ok, value["access_token"]}
      %Right{value: value} -> {:error, value}
    end
  end
end
