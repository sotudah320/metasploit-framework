# -*- coding: binary -*-
module Msf

require 'socket'

###
#
# Network address option.
#
###
class OptAddressLocal < OptAddress
  def normalize(value)
    return nil unless value.kind_of?(String)

    interfaces = Socket.getifaddrs.map(&:name).compact.uniq
    if interfaces.include?(value)
      ip_addresses = Socket.getifaddrs.map { |i| i.addr.ip_address if i.addr.ip? }.compact.uniq
      return false if ip_address.blank?
      return ip_address.first
    end

    return value
  end

  def valid?(value, check_empty: true)
    return false if check_empty && empty_required_value?(value)
    return false unless value.kind_of?(String) or value.kind_of?(NilClass)

    return true if NetworkInterface.interfaces.include?(value)

    return super
  end
end

end
