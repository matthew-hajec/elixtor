defmodule Channel.Cells.Versions do
  @moduledoc """
  The Channel.Cells.Versions module represents the VERSIONS cell type in the Tor protocol.
  """

  @behaviour Channel.CellBehaviour

  @type t :: %__MODULE__{
          versions: [integer()]
        }

  defstruct [
    :versions
  ]

  def from_binary_cell(cell) do
    # Parse the available versions
    case parse_versions(cell.payload) do
      {:ok, versions} -> {:ok, %__MODULE__{versions: versions}}
      {:error, _} = error -> error
    end
  end

  # Versions is a series of 2-byte big-endian integers with no terminator.
  defp parse_versions(<<version::16, rest::binary>>) do
    parse_versions(rest, [version])
  end

  defp parse_versions(<<version::16, rest::binary>>, acc) do
    parse_versions(rest, [version | acc])
  end

  defp parse_versions(<<>>, acc) do
    {:ok, Enum.reverse(acc)}
  end

  defp parse_versions(_, _), do: {:error, :invalid_format}

  def from_keywords(keywords) do
    versions = keywords[:versions]

    # Make sure the versions are valid (1-5)
    if Enum.any?(versions, fn version -> version < 1 or version > 5 end) do
      {:error, :invalid_version}
    end

    {:ok, %__MODULE__{versions: versions}}
  end

  def to_binary_cell(versions_cell) do
    # Convert the versions to a binary
    versions = versions_cell.versions

    versions_binary =
      Enum.reduce(versions, <<>>, fn version, acc -> <<acc::binary, version::16>> end)

    # Create the cell
    {:ok, Channel.BinaryCell.new(0, 7, versions_binary)}
  end
end
