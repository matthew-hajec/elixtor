defmodule Channel.Parsing.Certs do
  @moduledoc """
  The Channel.Parsing.Certs module provides functions for parsing Tor CERTS cells.
  """

  defstruct [
    :version,
    :cert_type,
    :expiration_date,
    :cert_key_type,
    :certified_key,
    :extensions,
    :signature,
    :pre_sig
  ]

  def parse_certs(%Channel.Cell{payload: payload}) do
    parse_certs(payload)
  end

  def parse_certs(<<num_certs::8, rest::binary>>) do
    parse_certs(num_certs, rest, [])
  end

  defp parse_certs(0, _rest, acc), do: {:ok, Enum.reverse(acc)}

  # Handle Ed25519 certs
  defp parse_certs(num_certs, <<cert_type::8, cert_len::16, cert::binary-size(cert_len), rest::binary>>, acc) when cert_type in [4, 5, 6, 8, 9, 10, 11] do
    case Channel.Parsing.Certs.Ed25519.parse(cert) do
      {:ok, parsed_cert} -> parse_certs(num_certs - 1, rest, [{cert_type, parsed_cert} | acc])
      {:error, _} = error -> error
    end
  end

  # Handle RSA certs
  defp parse_certs(num_certs, <<cert_type::8, cert_len::16, cert::binary-size(cert_len), rest::binary>>, acc) do
    parse_certs(num_certs - 1, rest, [{cert_type, cert} | acc])
  end

  defp parse_certs(_, _, _), do: {:error, :invalid_format}


end
