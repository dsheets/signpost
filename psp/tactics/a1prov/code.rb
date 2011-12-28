#! /usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'net/dns/resolver'
require 'lib/tactic_solver/tactic_helper'

tactic = TacticHelper.new

tactic.when :b1 do |helper, truths|
  # This truth isn't cached
  helper.provide_truth truths[:what][:value], true, 0, true
  helper.recycle_tactic  
end

# We need to initialize the tactic, otherwise nothing will ever happen
tactic.run
