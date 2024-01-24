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
    case parse_versions(cell.payload) do
      {:ok, versions} -> {:ok, %__MODULE__{versions: versions}}
      {:error, _} = error -> error
    end
  end

  # A VERSIONS cell contains a list of link protocol versions. Each version is 16 bits long.
  defp parse_versions(binary), do: parse_versions(binary, [])

  defp parse_versions(<<version::16, rest::binary>>, acc),
    do: parse_versions(rest, [version | acc])

  # Rest is empty, so we're done
  defp parse_versions(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  # Error if previous pattern matching fails
  defp parse_versions(_, _), do: {:error, :invalid_format}

  def from_keywords(keywords) do
    versions = keywords[:versions]

    if Enum.all?(versions, &valid_version?/1) do
      {:ok, %__MODULE__{versions: versions}}
    else
      {:error, :invalid_version}
    end
  end

  defp valid_version?(version), do: version >= 1 and version <= 5

  def to_binary_cell(versions_cell) do
    # Convert the versions to a binary
    versions = versions_cell.versions

    versions_binary =
      Enum.reduce(versions, <<>>, fn version, acc -> <<acc::binary, version::16>> end)

    # Create the cell
    {:ok, Channel.BinaryCell.new(0, 7, versions_binary)}
  end
end
