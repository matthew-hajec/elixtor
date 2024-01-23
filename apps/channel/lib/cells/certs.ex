defmodule Channel.Cells.Certs do
  @moduledoc """
  The Channel.Cells.Certs module represents the CERTS cell type in the Tor protocol.

  Currently, only Ed25519 certs are properly parsed, all other cert types are returned as binaries.
  """

  @behaviour Channel.CellBehaviour

  @type t :: %__MODULE__{
          version: integer(),
          cert_type: integer(),
          expiration_date: integer(),
          cert_key_type: integer(),
          certified_key: binary,
          extensions: [%{}],
          signature: binary,
          pre_sig: binary
        }

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

  def from_binary_cell(cell) do
    parse_certs(cell.payload)
  end

  defp parse_certs(<<num_certs::8, rest::binary>>) do
    parse_certs(num_certs, rest, [])
  end

  defp parse_certs(0, _rest, acc), do: {:ok, Enum.reverse(acc)}

  # Handle Ed25519 certs
  defp parse_certs(num_certs, <<cert_type::8, cert_len::16, cert::binary-size(cert_len), rest::binary>>, acc) when cert_type in [4, 5, 6, 8, 9, 10, 11] do
    case parse_ed25519(cert) do
      {:ok, parsed_cert} -> parse_certs(num_certs - 1, rest, [{cert_type, parsed_cert} | acc])
      {:error, _} = error -> error
    end
  end

  # Handle other certs
  defp parse_certs(num_certs, <<cert_type::8, cert_len::16, cert::binary-size(cert_len), rest::binary>>, acc) do
    parse_certs(num_certs - 1, rest, [{cert_type, cert} | acc])
  end

  defp parse_certs(_, _, _), do: {:error, :invalid_format}

  defp parse_ed25519(<<version::8, cert_type::8, expiration_date::32, cert_key_type::8, certified_key::binary-size(32), num_extensions::8, rest::binary>> = full_cert) do
    case parse_ed25519_extensions(num_extensions, rest, []) do
      {:ok, extensions, <<signature::binary-size(64)>>} ->
        # Calculate the length of the bytes prior to the signature
        pre_sig_len = byte_size(full_cert) - 64
        # Extract the bytes prior to the signature
        <<pre_sig::binary-size(pre_sig_len), _::binary>> = full_cert
        {:ok, %Channel.Cells.Certs{
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

  defp parse_ed25519_extensions(0, rest, acc), do: {:ok, Enum.reverse(acc), rest}

  defp parse_ed25519_extensions(num_extensions, <<ext_len::16, ext_type::8, ext_flags::8, ext_data::binary-size(ext_len), rest::binary>>, acc) do
    parse_ed25519_extensions(num_extensions - 1, rest, [%{ext_type: ext_type, ext_flags: ext_flags, ext_data: ext_data} | acc])
  end

  defp parse_ed25519_extensions(_, _, _), do: {:error, :invalid_format}

  def to_binary_cell(_any) do
    {:ok, Channel.BinaryCell.new(0, 7, <<3::16>>)}
  end
end
