.CODE
main PROC
    test eax, eax
    jz done
    jb done
    cmp eax, 0
    jz done
    jne done
done:
    ret
main ENDP
END
