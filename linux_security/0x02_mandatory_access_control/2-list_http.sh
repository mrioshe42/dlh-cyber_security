#!/bin/bash
grep http <(semanage port -l)
