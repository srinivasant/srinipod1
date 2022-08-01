[!] Unknown command: `=`

Usage:

    $ pod trunk register EMAIL [YOUR_NAME]

      Register a new account, or create a new session.

      If this is your first registration, both an `EMAIL` address and `YOUR_NAME` are
      required. If you’ve already registered with trunk, you may omit the `YOUR_NAME`
      (unless you would like to change it).

      It is recommended that you provide a description of the session, so that it will
      be easier to identify later on. For instance, when you would like to clean-up
      your sessions. A common example is to specify the location where the machine,
      that you are using the session for, is physically located.

      Examples:

          $ pod trunk register eloy@example.com 'Eloy Durán' --description='Personal Laptop'
          $ pod trunk register eloy@example.com --description='Work Laptop'
          $ pod trunk register eloy@example.com

Options:

    --description=DESCRIPTION   An arbitrary description to easily identify your
                                session later on.
    --allow-root                Allows CocoaPods to run as root
    --silent                    Show nothing
    --verbose                   Show more debugging information
    --no-ansi                   Show output without ANSI codes
    --help                      Show help banner of specified command
