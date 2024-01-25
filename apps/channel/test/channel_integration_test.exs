defmodule ChannelIntegrationTest do
  use ExUnit.Case
  #doctest Channel.BinaryCell

  @ip_ports [{{162, 55, 91, 19}, 443}]

  # Create a Channel struct with a TLS socket connected to a Tor relay
  setup do
    socket = Enum.reduce_while(@ip_ports, nil, fn {ip, port}, _acc ->
      case :ssl.connect(ip, port, [:binary, active: false, verify: :verify_none]) do
        {:ok, socket} -> {:halt, socket}
        _ -> {:cont, nil}
      end
    end)

    case socket do
      nil -> {:error, :no_available_port}
      _ -> {:ok, %{channel: Channel.new(socket)}}
    end
  end

  # Test if the socket is connected by receiving 0 bytes from it
  defp is_socket_connected?(socket) do
    case :ssl.recv(socket, 0, 0) do
      {:ok, _} -> true
      {:error, :closed} -> false
      _ -> false
    end
  end

  @tag :integration
  test "defualt circ_id_len is 16", %{channel: ch} do
    assert ch.circ_id_len == 16
  end

  @tag :integration
  test "performs an unauthenticated client side handshake", %{channel: ch} do
    # Send VERSIONS
    {:ok, versions_cell} = Channel.Cells.Versions.from_keywords versions: [3]
    Channel.convert_and_send(ch, versions_cell, Channel.Cells.Versions)

    # Receive VERSIONS
    {:ok, _} = Channel.recv_and_convert(ch, Channel.Cells.Versions)

    # Receive CERTS
    {:ok, _} = Channel.recv_and_convert(ch, Channel.Cells.Certs)

    # Receive AUTH_CHALLENGE
    {:ok, _} = Channel.recv_cell(ch)

    # Send NETINFO
    cell = Channel.BinaryCell.new(0, 8, <<0::32, 4, 4, 162, 55, 91, 19, 1, 4, 4, 0, 0, 0, 0>>) # NETINFO
    :ok = Channel.send_cell(ch, cell)


    # Test if the socket is connected
    assert is_socket_connected?(ch.tls_socket)
  end
end
