defmodule Channel.CellBehaviour do
  @moduledoc """
  Defines behaviour for converting between binary cells and specific cell types.

  The `any()` type is used liberally in the callbacks to allow for flexibility in the implementation.
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
