defmodule Channel.CellBehaviour do
  @moduledoc """
  Defines behaviour for converting between binary cells and specific cell types.

  The `any()` type is used liberally in the callbacks to allow for flexibility in the implementation.
  """

  @callback from_binary_cell(Channel.BinaryCell.t()) :: {:ok, any()} | {:error, any()}
  @callback to_binary_cell(any()) :: {:ok, Channel.BinaryCell.t()} | {:error, any()}
end
