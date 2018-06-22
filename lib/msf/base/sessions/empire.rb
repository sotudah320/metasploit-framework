# -*- coding: binary -*-

require 'msf/base/sessions/command_shell'

module Msf::Sessions
  class EmpireShell < Msf::Sessions::CommandShell

    include Msf::Session::Basic
    include Msf::Session::Provider::SingleCommandShell

    def initialize(*args)
      self.arch = ARCH_CMD
      super
    end

    def desc
      "Empire Shell (#{self.platform})"
    end

    def self.type
      "empire"
    end
  end

  class EmpireWindowsShell < EmpireShell
    def initialize(*args)
      self.platform = 'windows'
      super
    end
  end

  class EmpireOSXShell < EmpireShell
    def initialize(*args)
      self.platform = 'osx'
      super
    end
  end

  class EmpireLinuxShell < EmpireShell
    def initialize(*args)
      self.platform = 'linux'
      super
    end
  end
end
