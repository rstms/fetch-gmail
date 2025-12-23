# fetch-gmail

fetch-gmail implements two subcommands:
gen: generates a fetchmailrc configured to use the plugin
plugin: a fetchmail plugin that manages manages the TLS connnection
to the host and implements XOATH2 Authentication in the IMAP login
sequence using an access token queried from the tokend server
