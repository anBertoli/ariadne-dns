###TODO
- Improve cache: don't use (String, dns::RecordType) as key since doesn't work well with the Borrow trait.
- Add a stub resolver? It simply forwards request to another resolver.