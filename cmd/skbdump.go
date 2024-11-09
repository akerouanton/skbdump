package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/akerouanton/skbdump/pkg/skbdump"
	"github.com/cilium/cilium/pkg/time"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

func parseFlags(fl flags) (writer, error) {
	if fl.outfile == "" {
		return writer{write: skbdump.PrintSKB}, nil
	}

	f := os.Stdout
	if fl.outfile != "-" {
		var err error
		f, err = os.OpenFile(fl.outfile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return writer{}, err
		}
	}

	w, err := skbdump.NewPCAPWriter(f)
	if err != nil {
		return writer{}, fmt.Errorf("creating pcap writer: %w", err)
	}

	return writer{
		f: f,
		w: w,
		write: func(skb skbdump.SKB) error {
			if err := w.WriteSKB(skb); err != nil {
				return err
			}
			// TODO(aker): do we need to forcefully flush after each write?
			return w.Flush()
		},
	}, nil
}

type flags struct {
	outfile string
}

func main() {
	var f flags

	cmd := &cobra.Command{
		Use:     "Dump packets by hooking into the kernel",
		Version: "v0.1",
		Run: func(cmd *cobra.Command, args []string) {
			var filter string
			if len(args) > 0 {
				filter = args[0]
			}

			if err := run(f, filter); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR:", err.Error())
				os.Exit(1)
			}

			return
		},
		Args: cobra.MaximumNArgs(1),
	}

	cmd.Flags().StringVarP(&f.outfile, "write", "w", "", "pcap file to write to")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(f flags, filter string) error {
	w, err := parseFlags(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err.Error())
		os.Exit(1)
	}
	defer w.Close()

	d, err := skbdump.NewDumper(skbdump.Config{
		Filter: filter,
		CGroup: "/sys/fs/cgroup/docker",
	})
	if err != nil {
		return err
	}
	defer d.Close()

	eg, ctx := errgroup.WithContext(context.Background())

	skbch := make(chan skbdump.SKB, 1000)
	eg.Go(func() error {
		return d.Run(skbch)
	})

	eg.Go(func() error {
		tickD := 5 * time.Second
		ticker := time.NewTicker(tickD)
		var lastMisses uint
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				misses := d.QueryMisses()
				if misses != lastMisses {
					fmt.Fprintf(os.Stderr, "WARNING: %d SKBs missed in the last %.0f seconds\n", misses-lastMisses, tickD.Seconds())
					lastMisses = misses
				}
			}
		}
	})

	eg.Go(func() error {
		fmt.Fprintln(os.Stderr, "Ready to receive SKBs...")
		for {
			select {
			case <-ctx.Done():
				return nil
			case skb, ok := <-skbch:
				if !ok {
					return nil
				}
				if err := w.write(skb); err != nil {
					return err
				}
			}
		}
	})

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)
	errExiting := fmt.Errorf("exiting")
	eg.Go(func() error {
		select {
		case <-ctx.Done():
			// If another goroutine returns an error - tear everything down.
		case <-sigch:
			fmt.Fprintln(os.Stderr, "Exiting...")
		}

		d.Close() // Close the skbdump to interrupt any map-reading blocking syscall.
		close(skbch)

		return errExiting // Return an error to stop the errgroup.
	})

	if err := eg.Wait(); !errors.Is(err, errExiting) {
		return err
	}
	return nil
}
