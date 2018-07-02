# -*- coding: binary -*-
require 'rex/socket'
require 'thread'

module Msf
module Handler
###
#
# This module implements the reverse TCP handler.  This means
# that it listens on a port waiting for a connection until
# either one is established or it is told to abort.
#
# This handler depends on having a local host and port to
# listen on.
#
###
module EmpireReverseTcp
  include Msf::Handler
  include Msf::Handler::Reverse
  include Msf::Handler::Reverse::Comm

  #
  # Returns the string representation of the handler type, in this case
  # 'reverse_tcp'.
  #
  def self.handler_type
    "reverse_tcp"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'reverse'.
  #
  def self.general_handler_type
    "reverse"
  end

  #
  # Initializes the reverse TCP handler and ads the options that are required
  # for all reverse TCP payloads, like local host and local port.
  #
  def initialize(info = {})
    super

    # Register options here
    register_advanced_options(
      [
        OptAddress.new(
          'ReverseListenerBindAddress',
          [ false, 'The specific IP address to bind to on the local system' ]
        ),
        OptBool.new(
          'ReverseListenerThreaded',
          [ true, 'Handle every connection in a new thread (experimental)', false ]
        )
      ] +
      Msf::Opt::stager_retry_options,
      Msf::Handler::ReverseTcp
    )
  end

  #
  # Closes the listener socket if one was created.
  #
  def cleanup_handler
    stop_handler

    # Kill any remaining handle_connection threads that might
    # be hanging around
    listener_thread.kill
  end

  # A string suitable for displaying to the user
  #
  # @return [String]
  def human_name
    "reverse TCP"
  end

  # A URI describing what the payload is configured to use for transport
  def payload_uri
    addr = datastore['LHOST']
    uri_host = Rex::Socket.is_ipv6?(addr) ? "[#{addr}]" : addr
    "tcp://#{uri_host}:#{datastore['LPORT']}"
  end

  # A URI describing where we are listening
  #
  # @param addr [String] the address that
  # @return [String] A URI of the form +scheme://host:port/+
  def listener_uri(addr = datastore['ReverseListenerBindAddress'])
    addr = datastore['LHOST'] if addr.nil? || addr.empty?
    uri_host = Rex::Socket.is_ipv6?(addr) ? "[#{addr}]" : addr
    "tcp://#{uri_host}:#{bind_port}"
  end

  #
  # Starts monitoring for an inbound connection.
  #
  def start_handler
    queue = ::Queue.new

    local_port = bind_port

    # start empire listener here (thread below optional)

    handler_name = "EmpireReverseTcpHandlerListener-#{local_port}"
    self.listener_thread = framework.threads.spawn(handler_name, false, queue) { |lqueue|
      loop do
        #
        sleep 1
      end
    }
  end

  #
  # Stops monitoring for an inbound connection.
  #
  def stop_handler
    # Terminate the listener thread
    listener_thread.kill if listener_thread && listener_thread.alive? == true

    # Terminate the handler thread
    handler_thread.kill if handler_thread && handler_thread.alive? == true

    begin
      listener_sock.close if listener_sock
    rescue IOError
      # Ignore if it's listening on a dead session
      dlog("IOError closing listener sock; listening on dead session?", LEV_1)
    end
  end

  protected

  attr_accessor :listener_sock # :nodoc:
  attr_accessor :listener_thread # :nodoc:
  attr_accessor :handler_thread # :nodoc:
end
end
end
