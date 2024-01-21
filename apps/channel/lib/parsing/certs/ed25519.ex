defmodule Channel.Parsing.Certs.Ed25519 do
  @moduledoc """
  The Channel.Parsing.Certs.Ed25519 module provides functions for parsing Ed25519 certs from a CERTS cell.
  """

  def parse(<<version::8, cert_type::8, expiration_date::32, cert_key_type::8, certified_key::binary-size(32), num_extensions::8, rest::binary>> = full_cert) do
    case parse_extensions(num_extensions, rest, []) do
      {:ok, extensions, <<signature::binary-size(64)>>} ->
        # Calculate the length of the bytes prior to the signature
        pre_sig_len = byte_size(full_cert) - 64
        # Extract the bytes prior to the signature
        <<pre_sig::binary-size(pre_sig_len), _::binary>> = full_cert
        {:ok, %Channel.Parsing.Certs{
          version: version,
          cert_type: cert_type,
          expiration_date: expiration_date,
          cert_key_type: cert_key_type,
          certified_key: certified_key,
          extensions: extensions,
          signature: signature,
          pre_sig: pre_sig
        }}
      _ ->
        {:error, :invalid_format}
    end
  end

  defp parse_extensions(0, rest, acc), do: {:ok, Enum.reverse(acc), rest}

  defp parse_extensions(num_extensions, <<ext_len::16, ext_type::8, ext_flags::8, ext_data::binary-size(ext_len), rest::binary>>, acc) do
    parse_extensions(num_extensions - 1, rest, [%{ext_type: ext_type, ext_flags: ext_flags, ext_data: ext_data} | acc])
  end

  defp parse_extensions(_, _, _), do: {:error, :invalid_format}
end
