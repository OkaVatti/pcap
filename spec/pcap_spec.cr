require "./spec_helper"

describe LibPcap do
  it "reports a version string" do
    LibPcap.version.should be_a(String)
    LibPcap.version.should_not be_empty
  end
end
