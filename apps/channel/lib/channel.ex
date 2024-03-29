defmodule Channel do
  @moduledoc """
  The Channel module handles the communication between nodes in a network.

  It provides functions to send and receive cells over a secure SSL socket, and other functions related to establishing and using a channel.

  As of now, link protocols other than version 3 are not explicitly supported.

  You can read more about Channels in the Tor spec: https://spec.torproject.org/tor-spec/channels.html


  ## Example
  ```elixir
  # Open a TLS socket with a relay
  {:ok, tls} = :ssl.connect({162, 55, 91, 19}, 443, [:binary, active: false, verify: :verify_none])

  # Create a channel struct
  ch = Channel.new(tls)

  # Create a versions cell
  {:ok, versions_cell} = Channel.Cells.Versions.from_keywords versions: [3]

  # Send the versions cell over the channel
  Channel.convert_and_send(ch, versions_cell, Channel.Cells.Versions)

  # Recevie a versions cell from the server
  {:ok, versions_cell} = Channel.recv_and_convert(ch, Channel.Cells.Versions)
  ```

  """

  @typedoc """
  A channel is a TLS connection to a Tor relay, the width of the cird_id is negotiated during the handshake.
  """
  @type t :: %__MODULE__{
          tls_socket: :ssl.socket(),
          circ_id_len: 16 | 32
        }

  defstruct [
    :tls_socket,
    :circ_id_len
  ]

  @doc """
  Creates a new channel with the given TLS socket.
  """
  @spec new(:ssl.socket()) :: Channel.t()
  def new(tls_socket) do
    %Channel{
      tls_socket: tls_socket,
      # 16 is the default length of the circ_id, in bits, 32 can be negotiated, see https://spec.torproject.org/tor-spec/subprotocol-versioning.html#link
      circ_id_len: 16
    }
  end

  @doc """
  Validates the TLS certificate of the given channel against the given signing certificate.

  This function DOES NOT validate the certificate chain, it only checks if the subject matches.
  """
  @spec check_tls_hash(Channel.t(), Channel.Parsing.Certs.t()) :: :ok | {:error, any()}
  def check_tls_hash(channel, signing_v_tls_cert) when signing_v_tls_cert.cert_type == 5 do
    # Get the peer certificate from the TLS socket
    case :ssl.peercert(channel.tls_socket) do
      {:ok, der_cert} ->
        # Hash the DER-encoded certificate with SHA-256
        cert_hash = :crypto.hash(:sha256, der_cert)

        # Compare the hash to signing_v_tls_cert.certified_key
        if cert_hash == signing_v_tls_cert.certified_key do
          :ok
        else
          {:error, :cert_mismatch}
        end

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Converts a cell of a specific type into a binary cell and sends it over the given channel.

  The cell is converted to a binary cell by the given cell module.

  For example, to send a VERSIONS cell:

      cell = Channel.Cells.Versions.new([1, 2, 3])
      Channel.convert_and_send(channel, cell, Channel.Cells.Versions)
  """
  @spec convert_and_send(Channel.t(), struct(), Channel.CellBehaviour) ::
          :ok | {:error, :ssl.reason()}
  def convert_and_send(ch, cell, cell_mod) do
    case cell_mod.to_binary_cell(cell) do
      {:ok, new_cell} -> send_cell(ch, new_cell)
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Receives a cell and converts it to a struct using the given cell module.

  For example, to receive a VERSIONS cell:

      {:ok, versions_cell} = Channel.recv_and_convert(channel, Channel.Cells.Versions)
  """
  @spec recv_and_convert(Channel.t(), Channel.CellBehaviour) ::
          {:ok, struct()} | {:error, :ssl.reason()}
  def recv_and_convert(ch, cell_mod) do
    with {:ok, cell} <- recv_cell(ch) do
      cell_mod.from_binary_cell(cell)
    end
  end

  @doc """
  Sends the given cell over the given channel.
  """
  @spec send_cell(Channel.t(), Channel.BinaryCell.t()) :: :ok | {:error, :ssl.reason()}
  def send_cell(channel, cell) do
    cell_bytes =
      if Channel.BinaryCell.variable_payload?(cell.command) do
        # Include the length of the payload in the cell
        <<cell.circ_id::size(channel.circ_id_len), cell.command::8, byte_size(cell.payload)::16,
          cell.payload::binary>>
      else
        # Don't include the length of the payload in the cell, pad the payload to 509 bytes
        padded_payload = String.pad_trailing(cell.payload, 509, "\x00")
        <<cell.circ_id::size(channel.circ_id_len), cell.command::8, padded_payload::binary>>
      end

    :ssl.send(channel.tls_socket, cell_bytes)
  end

  @doc """
  Receives the next cell from the given channel in the order they were received.
  """
  @spec recv_cell(Channel.t()) :: {:ok, Channel.BinaryCell.t()} | {:error, :ssl.reason()}
  def recv_cell(channel) do
    with {:ok, {circ_id, cmd, payload_type}} <- recv_cell_header(channel),
         {:ok, payload} <- recv_cell_payload(channel, payload_type) do
      {:ok, Channel.BinaryCell.new(circ_id, cmd, payload)}
    end
  end

  defp recv_cell_header(channel) do
    case :ssl.recv(channel.tls_socket, trunc(channel.circ_id_len / 8) + 1) do
      {:ok, <<circ_id::size(channel.circ_id_len), cmd::8>>} ->
        if Channel.BinaryCell.variable_payload?(cmd) do
          {:ok, {circ_id, cmd, :variable}}
        else
          {:ok, {circ_id, cmd, :fixed}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp recv_cell_payload(channel, :fixed) do
    # For fixed length payloads, read 509 bytes but strip the padding
    with {:ok, payload} <- :ssl.recv(channel.tls_socket, 509) do
      # strip padding
      payload = payload |> String.trim_trailing("\x00")
      {:ok, payload}
    end
  end

  defp recv_cell_payload(channel, :variable) do
    # For variable length payloads, read the length of the payload, then read the payload
    with {:ok, <<len::16>>} <- :ssl.recv(channel.tls_socket, 2),
         {:ok, <<payload::binary>>} <- :ssl.recv(channel.tls_socket, len) do
      {:ok, payload}
    end
  end
end
