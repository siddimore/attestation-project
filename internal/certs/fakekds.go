package certs

import "os"

type FakeKDS struct{}

func (f *FakeKDS) GetVCEK() ([]byte, error) {
	// TODO: replace with AMD KDS endpoint
	return os.ReadFile("testdata/vcek.pem")
}

func (f *FakeKDS) GetARK() ([]byte, error) {
	// TODO: replace with AMD KDS endpoint
	return os.ReadFile("testdata/ark.pem")
}

func (f *FakeKDS) GetASK() ([]byte, error) {
	// TODO: replace with AMD KDS endpoint
	return os.ReadFile("testdata/ask.pem")
}
