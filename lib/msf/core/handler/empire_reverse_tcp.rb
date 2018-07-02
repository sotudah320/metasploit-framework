# -*- coding: binary -*-
require 'rex/socket'
require 'thread'

module Msf
  module Handler
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
        # start empire listener here

      end

      #
      # Stops monitoring for an inbound connection.
      #
      def stop_handler
        # stop empire listener here
      end

      #
      # Closes the listener socket if one was created.
      #
      def cleanup_handler
        stop_handler
      end
    end
  end
end
