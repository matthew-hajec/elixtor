defmodule Channel.Cell do
  @moduledoc """
  The Channel.Cell module represents the basic unit of communication in the Tor protocol.

  Each cell consists of a circuit ID, a command, and a payload. The circuit ID identifies the circuit that the cell belongs to. The command indicates the type of the cell. The payload contains the actual data of the cell.

  Cells can be variable or fixed length, it is up to the sender to parse the type of cell correctly. The function `variable_payload?/1` can be used to determine if a cell has a fixed or variable length payload.
  The circ_id can be either 16 or 32 bits long, this depends on the negotiated link protocol version, and the sender must know which to use.

  See https://spec.torproject.org/tor-spec/cell-packet-format.html for more details about the cell packet format in the Tor protocol.
  """

  @typedoc """
  Type for a cell.
  """
  @type t :: %__MODULE__{
          circ_id: integer(),
          command: integer(),
          payload: binary()
        }

  defstruct [
    :circ_id,
    :command,
    :payload
  ]

  @doc """
  Creates a cell

  Examples:
    iex> Channel.Cell.new(1, 7, <<1::16,2::16,3::16>>)
    %Channel.Cell{
      circ_id: 1,
      command: 7,
      payload: <<1::16,2::16,3::16>>
    }
    iex> Channel.Cell.new(1, 1, <<1::16,2::16,3::16>>)
    %Channel.Cell{
      circ_id: 1,
      command: 1,
      payload: <<1::16,2::16,3::16>>
    }
  """
  @spec new(integer(), integer(), binary()) :: Channel.Cell.t()
  def new(circ_id, command, payload) do
    # If the payload is fixed, make sure it's 509 bytes long (pad with null bytes, reject if too long)
    if !variable_payload?(command) && byte_size(payload) > 509 do
      raise "Fixed length payloads must be 509 bytes or less."
    end

    %Channel.Cell{
      circ_id: circ_id,
      command: command,
      payload: payload
    }
  end

  @doc """
  Determines if a cell has a variable length payload based on the command.

  Examples:
    iex> Channel.Cell.variable_payload?(7)
    true
    iex> Channel.Cell.variable_payload?(128)
    true
    iex> Channel.Cell.variable_payload?(127)
    false

  """
  @spec variable_payload?(integer) :: boolean()
  def variable_payload?(cmd) do
    # >= 128 is variable, < 128 is fixed, except 7, which is variable
    cmd >= 128 || cmd == 7
  end
end
