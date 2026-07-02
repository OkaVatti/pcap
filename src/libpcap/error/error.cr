# Exception hierarchy for libpcap operations.
#
# All errors from the C library are translated into Crystal exceptions.
# This provides clear, typed errors that integrate with Crystal's `begin ... rescue`.
module LibPcap
  class Error < Exception
    # The underlying libpcap error string (if available)
    getter pcap_error : String?

    def initialize(message : String, pcap_error : String? = nil)
      super(message)
      @pcap_error = pcap_error
    end
  end

  # Raised when a device or savefile cannot be opened.
  class OpenError < Error; end

  # Raised when a capture configuration option fails.
  class ConfigurationError < Error; end

  # Raised when activating a handle fails.
  class ActivationError < Error; end

  # Raised when compiling or setting a BPF filter fails.
  class FilterError < Error; end

  # Raised when the capture loop is explicitly broken by `PcapHandle#breakloop`.
  class BreakLoopError < Error
    def initialize
      super("Capture loop was explicitly broken")
    end
  end

  # Raised when an operation times out (only relevant for some rare cases).
  class TimeoutError < Error; end

  # Wrapper for `Result(T)` pattern when errors are expected.
  #
  # Example:
  #   result = handle.next_packet
  #   case result
  #   when .ok?   then packet = result.value
  #   when .eof?  then puts "End of file"
  #   when .error? then puts "Error: #{result.error}"
  #   end
  struct Result(T)
    enum Kind
      Ok
      Eof
      Error
    end

    getter kind : Kind
    getter value : T?
    getter error : Error?

    def initialize(@kind : Kind, @value : T? = nil, @error : Error? = nil)
    end

    # Constructors for each case
    def self.ok(value : T) : self
      new(Kind::Ok, value: value)
    end

    def self.eof : self
      new(Kind::Eof)
    end

    def self.error(error : Error) : self
      new(Kind::Error, error: error)
    end

    # Predicates
    def ok? : Bool
      @kind == Kind::Ok
    end

    def eof? : Bool
      @kind == Kind::Eof
    end

    def error? : Bool
      @kind == Kind::Error
    end

    # Returns the value on Ok, raises on Eof or Error.
    # Uses if-elsif with explicit type checks for proper type narrowing.
    def unwrap! : T
      if ok?
        @value.as(T)
      elsif eof?
        raise Error.new("Unexpected EOF, expected packet")
      elsif error?
        raise @error.as(Error)
      else
        raise Error.new("Unknown Result state")
      end
    end
  end
end
