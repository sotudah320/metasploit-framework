# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
  module Sessions

    ###
    #
    # This class creates a platform-specific meterpreter session type
    #
    ###
    class Meterpreter_Posix < Msf::Sessions::Meterpreter
      def initialize(rstream, opts={})
        super
        self.platform      = 'generic'
        self.binary_suffix = 'lso'
      end

      def supports_ssl?
        false
      end

      def supports_zlib?
        false
      end

    end
  end
end

