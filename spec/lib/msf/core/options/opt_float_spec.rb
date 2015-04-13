# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/option_container'

describe Msf::OptInt do
  valid_values = [
    { :value => "1.0",    :normalized => 1.0  },
    { :value => "10.0",   :normalized => 10.0 },
    { :value => "12e3",   :normalized => 12e3  },
    { :value => "-10.0",  :normalized => -10.0 },
    { :value => "-12e3",  :normalized => -12e3 },
  ]
  invalid_values = [
    { :value => "0x10", },
    { :value => "CAT",  },
    { :value => "0xG",  },
    { :value => "FF",   },
  ]

  it_behaves_like "an option", valid_values, invalid_values, 'float'
end


