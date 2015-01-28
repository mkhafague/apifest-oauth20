package com.apifest.oauth20.security;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class SubnetRange {
	private static Pattern pattern = Pattern.compile("[\\p{Blank},]");
	private List<SubnetUtils> ranges = new ArrayList<SubnetUtils>();
	
	private SubnetRange() {
	}
	
	/**
	 * Returns true if no allowedIPs set
	 */
	public boolean inRange(String addr) {
		if (ranges.isEmpty()) {
			return true;
		}

		for (SubnetUtils s : ranges) {
			if (s.getInfo().isInRange(addr))
				return true;
		}

		return false;
	}
	
	public static SubnetRange parse(String text) throws IllegalArgumentException {
		String[] cidrs = pattern.split(text);
		SubnetRange sr = new SubnetRange();
		
		for (String cidr : cidrs) {
			SubnetUtils net = new SubnetUtils(cidr);

			if (net == null) {
				throw new IllegalArgumentException("Invalid subnet : " + cidr);
			}

			sr.ranges.add(net);
		}

		return sr;
	}
}
