defmodule Elixtor.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixtor,
      apps_path: "apps",
      version: "0.2.0-beta",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Dependencies listed here are available only for this
  # project and cannot be accessed from applications inside
  # the apps folder.
  #
  # Run "mix help deps" for examples and options.
  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.31", only: [:dev, :docs], runtime: false}
    ]
  end
end
