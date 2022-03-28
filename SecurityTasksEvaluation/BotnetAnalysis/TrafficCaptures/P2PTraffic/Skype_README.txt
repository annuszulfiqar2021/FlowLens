*****IP configuration*****
natbox	128.192.76.184
reglinux_1	192.168.0.4
win7box_1	192.168.2.2
win7box_2	192.168.1.2
win7box_3	192.168.3.2
win7box_4	192.168.4.2
xpbox_1		192.168.6.2
xpbox_2		192.168.5.2
superlinux_1	128.192.76.181
superlinux_2	128.192.76.182
offcampusbox_1	97.81.96.137

Each box in the NAT is on it's own subnet to prevent communication
between the clients behind the NAT.

*****AutoIt script configurations*****
win7box_1	Upon initiation of the script, enters an infinite loop in
		which it places a call for 10 minutes then ends the call,
		waits for 2 hours 5 minutes, places a call for 5 minutes
		then ends the call, waits for 2 hours 10 minutes, and
		repeats.  The reason for the additional time in the 2 hour
		waiting period is to avoid collisions with the other box
		making calls.  By waiting during the duration of the other
		box's calls, collisions can be avoided.

xpbox_1		Upon initiation of the script, waits for 1 hour 10 minutes,
		then enters an infinite loop in which it places a call
		for 5 minutes then ends the call, waits for 2 hours 10 minutes,
		places a call for 10 minutes then ends the call, waits for
		2 hours 5 minutes, and repeats.  The collision avoidance
		measures are present in the wait times for this script as
		in the other so that they work in concert.

Both calling boxes also have microphones hooked up that are positioned under
the speaker on the underside of the machine.  The receiving box off campus
will play an iTunes radio feed to simulate voice data over the Skype network,
so the microphones are positioned to pick up the radio feed so that it will
be played back to the receiving box.

Receiving box:
offcampusbox_1	Requires iTunes to run alongside Skype, specifically with 
		iTunes radio open.  Any talk radio station will do.  The
		script waits in background for an incoming call, then answers
		the call and presses play on iTunes radio to start a radio
		feed. It waits 10 minutes then presses stop on iTunes to stop
		the radio feed.

IM boxes:
win7box_2	Upon initiation of the script, enters an infinite loop in
		which it sends a short message, waits 10 minutes, sends a long
		message, waits 2 hours, sends a long message, waits 1 hour,
		sends a short message, waits 2 hours, and repeats.  The timing
		measures in this script are designed to be complimentary to
		the script on win7box_2, so that they communicate in a
		back-and-forth manner.

win7box_3	Upon initiation of the script, enters an infinite loop in
		which it sends a short message, waits 10 minutes, sends a long
		message, waits 2 hours, sends a long message, waits 1 hour,
		sends a short message, waits 2 hours, and repeats.  The timing
		measures in this script are designed to be complimentary to
		the script on win7box_3, so that they communicate in a
		back-and-forth manner.

