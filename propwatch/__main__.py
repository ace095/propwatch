import sys

if len(sys.argv) > 1 and sys.argv[1] == "area":
    from .area import main
    main(sys.argv[2:])
else:
    from .nyc import main
    main()
