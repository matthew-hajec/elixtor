# Elixtor

## Example Usage

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



Tor client, built with Elixir.