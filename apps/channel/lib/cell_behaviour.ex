defmodule Channel.CellBehaviour do
  @moduledoc """
  Defines behaviour for converting between binary cells and specific cell types. Cells are differentiated
  by their command code.

  Tor provides a list of cell types with hyperlinks to the relevant sections of the Tor specification
  in section 2.3.2 "Cells (messages and channels)".
  """

  @doc """
  Convert a cell struct of the given type from a binary cell.

  If the binary cell's payload does not follow the expected schema or is otherwise invalid, an error MUST be returned.
  """
  @callback from_binary_cell(Channel.BinaryCell.t()) :: {:ok, struct()} | {:error, any()}
  @doc """
  Construct a cell of the given type given a keyword list of options.
  """
  @callback from_keywords(keyword()) :: {:ok, struct()} | {:error, any()}

  @doc """
  Convert a cell of the given type to a binary cell.
  """
  @callback to_binary_cell(struct()) :: {:ok, Channel.BinaryCell.t()} | {:error, any()}
end
