package sim

// SMSPush is the push of setupOBIS as the body of a binary SMS with the
// SMS short wrapper of the DLMS/COSEM SMS bearer: one octet of source
// address (the meter's management logical device, 1) and one of
// destination address (the push client), then the APDU.
func (m *Meter) SMSPush(setupOBIS string) ([]byte, error) {
	apdu, err := m.pushAPDU(setupOBIS)
	if err != nil {
		return nil, err
	}
	return append([]byte{0x01, byte(m.pushClient())}, apdu...), nil
}
